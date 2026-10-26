<!-- corpus: expect=PG-XSS-003 -->
<template>
  <div class="preview" v-html="html"></div>
</template>
<script setup>
import { computed } from "vue";
import { marked } from "marked";
const props = defineProps({ md: String });
const html = computed(() => marked(props.md));
</script>
