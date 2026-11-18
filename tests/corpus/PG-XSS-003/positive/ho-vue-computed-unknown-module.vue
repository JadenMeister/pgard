<!-- corpus: expect=PG-XSS-003 -->
<template>
  <div v-html="clean"></div>
</template>
<script setup>
import { computed } from "vue";
import { tidy } from "@/shared/markup";
const props = defineProps({ html: String });
// "@/shared/markup" is not a known sanitizer: the computed value is not proven clean.
const clean = computed(() => tidy(props.html));
</script>
