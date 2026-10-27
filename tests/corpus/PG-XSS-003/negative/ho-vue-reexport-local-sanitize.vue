<!-- corpus: expect=low -->
<template>
  <div v-html="sanitize(html)"></div>
</template>
<script setup>
import { sanitize } from "@/utils/sanitize";
defineProps({ html: String });
</script>
